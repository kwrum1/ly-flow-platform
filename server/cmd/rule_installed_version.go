package main

import (
	"context"
	"strings"
)

func installedRuleSourceVersion(ctx context.Context, cfg *Config, sourceID string) string {
	if cfg == nil || cfg.DBPool == nil {
		return ""
	}
	platformID := platformRuleSourceID(sourceID)
	if platformID == "" {
		return ""
	}
	var digest string
	err := cfg.DBPool.QueryRow(ctx, "SELECT content_hash FROM rule_source_versions WHERE source_id=$1 AND sync_status='synced' ORDER BY synced_at DESC NULLS LAST LIMIT 1", platformID).Scan(&digest)
	if err != nil {
		return ""
	}
	digest = strings.TrimSpace(digest)
	if len(digest) > 12 {
		digest = digest[:12]
	}
	if digest == "" {
		return ""
	}
	return "sha256-" + digest
}
