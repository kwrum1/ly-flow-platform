package main

import (
	"context"
	"errors"
	"testing"

	"github.com/lyflow/ly-flow-platform/server/incidentlifecycle"
)

type failingIncidentCheckpointer struct{}

func (failingIncidentCheckpointer) CheckpointLegacySnapshot(context.Context, []incidentlifecycle.LegacyStatus, string) (incidentlifecycle.SnapshotReport, error) {
	return incidentlifecycle.SnapshotReport{}, errors.New("checkpoint storage unavailable")
}

func TestCheckpointIncidentLifecycleOnShutdown_reports_degraded_history_without_cutover(t *testing.T) {
	// Given
	clearLegacyIncidentStatuses()
	incidentStatusStore.Store("inc-shutdown", "processing")
	t.Cleanup(clearLegacyIncidentStatuses)
	config := &Config{IncidentCheckpoint: failingIncidentCheckpointer{}, IncidentSnapshot: &incidentSnapshotState{}}

	// When
	report, err := checkpointIncidentLifecycleOnShutdown(context.Background(), config)

	// Then
	if err == nil {
		t.Fatal("failed shutdown checkpoint unexpectedly succeeded")
	}
	if report.CutoverMarked || report.Captured != 1 || report.Unrecoverable.Status != 1 || report.Unrecoverable.Assignee != 1 || report.Unrecoverable.Suppression != 1 || report.Unrecoverable.TransitionHistory != 1 {
		t.Fatalf("degraded shutdown report=%+v", report)
	}
	if config.IncidentSnapshot.err == nil || config.IncidentSnapshot.report.CutoverMarked {
		t.Fatalf("shutdown state did not retain explicit degradation: %+v", config.IncidentSnapshot)
	}
}

func TestIncidentLifecycleCheckpointRoute_is_admin_only(t *testing.T) {
	// When
	spec, found := findRouteSpec("/api/v1/admin/incident-lifecycle/checkpoint")

	// Then
	if !found || !rolesEqual(spec.ReadRoles, adminRoles) || !rolesEqual(spec.WriteRoles, adminRoles) {
		t.Fatalf("checkpoint route policy=%+v found=%v", spec, found)
	}
}
