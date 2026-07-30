package main

import (
	"context"
	"errors"

	"github.com/lyflow/ly-flow-platform/server/rulelifecycle"
)

type ruleBundleActivation struct {
	config  *Config
	actor   rulelifecycle.Actor
	version string
	digest  string
}

func (request ruleBundleActivation) activate(ctx context.Context) (rulelifecycle.ActiveManifest, error) {
	manifest, err := request.config.RuleLifecycle.ActivateWithManifestCommit(ctx, request.actor, request.version, func(candidate rulelifecycle.ActiveManifest) error {
		tx, beginErr := request.config.DBPool.Begin(ctx)
		if beginErr != nil {
			return beginErr
		}
		defer func() { _ = tx.Rollback(ctx) }()
		if _, updateErr := tx.Exec(ctx, `UPDATE rule_bundles SET status='inactive' WHERE status='active'`); updateErr != nil {
			return updateErr
		}
		if _, insertErr := tx.Exec(ctx, `INSERT INTO rule_bundles (version, status, bundle_hash, bundle_path, activated_at) VALUES ($1,'active',$2,$3,NOW()) ON CONFLICT (version) DO UPDATE SET status='active', bundle_hash=EXCLUDED.bundle_hash, bundle_path=EXCLUDED.bundle_path, activated_at=NOW()`, request.version, request.digest, candidate.BundlePath); insertErr != nil {
			return insertErr
		}
		if _, eventErr := tx.Exec(ctx, `INSERT INTO rule_hot_reload_events (bundle_version, target, status, message) VALUES ($1,$2,'ok',$3)`, request.version, "ly-security-engine", candidate.BundlePath); eventErr != nil {
			return eventErr
		}
		return tx.Commit(ctx)
	})
	if err == nil {
		return manifest, nil
	}
	if _, eventErr := request.config.DBPool.Exec(ctx, `INSERT INTO rule_hot_reload_events (bundle_version, target, status, message) VALUES ($1,$2,'failed',$3)`, request.version, "ly-security-engine", err.Error()); eventErr != nil {
		return rulelifecycle.ActiveManifest{}, errors.Join(err, eventErr)
	}
	return rulelifecycle.ActiveManifest{}, err
}
