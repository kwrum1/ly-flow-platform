package engine

import (
	"context"

	transport "github.com/lyflow/ly-flow-platform/transportreliability"
)

type Snapshot struct {
	Service          string                       `json:"service"`
	Status           string                       `json:"status"`
	Inputs           []string                     `json:"inputs"`
	Outputs          map[string]string            `json:"outputs"`
	BundleVersion    string                       `json:"bundle_version"`
	BundleDigest     string                       `json:"bundle_digest"`
	BundlePath       string                       `json:"bundle_path"`
	ManifestPath     string                       `json:"manifest_path"`
	RuleCounts       map[string]int               `json:"rule_counts"`
	Received         uint64                       `json:"received"`
	Alerts           uint64                       `json:"alerts"`
	DeadLetters      uint64                       `json:"dead_letters"`
	Reloads          uint64                       `json:"reloads"`
	Transport        transport.AccountingSnapshot `json:"transport"`
	TransportMetrics map[string]uint64            `json:"transport_metrics"`
	ControlHealth    RuntimeHealthSnapshot        `json:"control_health"`
}

func (e *Engine) Snapshot() Snapshot {
	return e.snapshot(e.reliable.Accounting())
}

func (e *Engine) SnapshotContext(ctx context.Context) (Snapshot, error) {
	_, integrityErr := e.VerifyIntegrity(ctx)
	accounting, accountingErr := e.reliable.AccountingContext(ctx)
	if accountingErr != nil {
		accounting = e.reliable.Accounting()
	}
	snapshot := e.snapshot(accounting)
	if integrityErr == nil && accountingErr == nil {
		return snapshot, nil
	}
	return snapshot, &SnapshotError{Integrity: integrityErr, Accounting: accountingErr}
}

func (e *Engine) snapshot(accounting transport.AccountingSnapshot) Snapshot {
	state := e.state.Load()
	bundle := state.bundle
	manifestPath, bundlePath := state.manifest.ManifestPath, state.manifest.BundlePath
	health := e.RuntimeHealth()
	status := "running"
	if health.Status == controlHealthDegraded {
		status = controlHealthDegraded
	}
	return Snapshot{Service: "ly-security-engine", Status: status, Inputs: e.cfg.InputStreams, Outputs: map[string]string{"dpi": e.cfg.DPIStream, "runtime": e.cfg.RuntimeStream, "rasp": e.cfg.RASPStream, "log_audit": e.cfg.LogAuditStream}, BundleVersion: bundle.Version, BundleDigest: bundle.Digest, BundlePath: bundlePath, ManifestPath: manifestPath, RuleCounts: bundle.Counts(), Received: e.stats.Received.Load(), Alerts: e.stats.Alerts.Load(), DeadLetters: e.stats.DeadLetters.Load(), Reloads: e.stats.Reloads.Load(), Transport: accounting, TransportMetrics: accounting.Metrics(), ControlHealth: health}
}
